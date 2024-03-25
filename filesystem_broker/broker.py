import concurrent.futures
import tempfile
import time
from pathlib import Path
from typing import Optional, List, Dict

from gitignore_parser import parse_gitignore

from git_file_client.client import Client as GitClient
from gitops_utils.utils import (
    Utils,
    FilePath,
    all_non_empty,
    is_nothing,
    match_file_extensions,
)


class Broker(Utils):
    def __init__(
        self,
        repository_owner: Optional[str] = None,
        repository_name: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)

        if repository_owner is None:
            repository_owner = self.get_input("repository_owner", required=False)

        if repository_name is None:
            repository_name = self.get_input("repository_name", required=False)

        if all_non_empty(repository_owner, repository_name):
            self.git_client = GitClient(
                github_owner=repository_owner, github_repo=repository_name, **kwargs
            )
        else:
            self.git_client = None

    def get_files(
        self,
        files: List[FilePath],
        relative_to_root: Optional[FilePath] = None,
        decode: bool = True,
        allowed_extensions: Optional[List[str]] = None,
        denied_extensions: Optional[List[str]] = None,
        charset: str = "utf-8",
        errors: str = "strict",
        headers: Optional[Dict[str, str]] = None,
        gitignore_file: Optional[FilePath] = None,
        match_dotfiles: bool = False,
    ):
        """Gets files either locally or from a repository"""
        if allowed_extensions is None:
            allowed_extensions = []

        if denied_extensions is None:
            denied_extensions = []

        if headers is None:
            headers = {}

        gitignore_matches = None
        delete_gitignore_file = False

        if self.git_client is None:
            if is_nothing(gitignore_file):
                gitignore_file = self.local_path(".gitignore")
            else:
                gitignore_file = Path(gitignore_file)
        else:
            gitignore_file_contents = self.git_client.get_repository_file(
                file_path=gitignore_file, decode=False
            )
            if not is_nothing(gitignore_file_contents):
                tmp_gitignore_file = tempfile.NamedTemporaryFile(delete=False)
                with open(tmp_gitignore_file.name, "w") as fh:
                    fh.write(gitignore_file_contents)

                gitignore_file = Path(tmp_gitignore_file.name)
                delete_gitignore_file = True

        if gitignore_file.exists():
            self.logged_statement(
                f"Matching files against gitignore file: {gitignore_file}"
            )
            gitignore_matches = parse_gitignore(gitignore_file)

        if delete_gitignore_file:
            gitignore_file.unlink(missing_ok=True)

        results = {}

        tic = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []

            for file in files:
                file_path = Path(file)

                if not match_dotfiles and file_path.name.startswith("."):
                    self.logged_statement(
                        f"Rejecting {file_path} because dotfiles are not being matched"
                    )
                    continue

                if (
                    len(allowed_extensions) > 0
                    and file_path.suffix not in allowed_extensions
                ) or file_path.suffix in denied_extensions:
                    self.logged_statement(f"Rejecting {file_path}")
                    continue

                if gitignore_matches is not None and gitignore_matches(
                    str(file_path.resolve())
                ):
                    self.logged_statement(
                        f"Rejecting {file_path} because of the gitignore file"
                    )
                    continue

                if self.git_client is None:
                    futures.append(
                        executor.submit(
                            self.get_file,
                            file_path=file_path,
                            decode=decode,
                            return_path=True,
                            charset=charset,
                            errors=errors,
                            headers=headers,
                            raise_on_not_found=True,
                        )
                    )
                else:
                    futures.append(
                        executor.submit(
                            self.git_client.get_repository_file,
                            file_path=file_path,
                            decode=decode,
                            return_path=True,
                            return_sha=False,
                            charset=charset,
                            errors=errors,
                            raise_on_not_found=True,
                        )
                    )

            for future in concurrent.futures.as_completed(futures):
                try:
                    file_data, file_path = future.result()
                    if not is_nothing(file_path):
                        self.logger.info(f"Successfully read {file_path}")

                        file_key = file_path
                        if relative_to_root:
                            file_key = Path(file_path).relative_to(relative_to_root)

                        file_key = str(file_key)

                        results[file_key] = file_data
                    else:
                        raise RuntimeError("Failed to get at least one file")
                except Exception as exc:
                    executor.shutdown(wait=False, cancel_futures=True)
                    raise RuntimeError(f"Failed to get files: {files}") from exc

        toc = time.perf_counter()
        self.logger.info(f"Getting files took {toc - tic:0.2f} seconds to run")

        self.logged_statement("Files", json_data=results, verbose=True, verbosity=2)

        return results

    def scan_dir(
        self,
        files_path: FilePath,
        files_glob: str = "*",
        files_match: Optional[str] = None,
        paths_only: bool = False,
        reject_dotfiles: bool = True,
        decode: bool = True,
        flatten: bool = False,
        sanitize_keys: bool = False,
        max_sanitize_depth: Optional[int] = None,
        stem_only: bool = False,
        recursive: bool = True,
        allowed_extensions: Optional[List[str]] = None,
        denied_extensions: Optional[List[str]] = None,
    ):
        """Scans a directory to get a tree of its files"""
        if allowed_extensions is None:
            allowed_extensions = []

        if denied_extensions is None:
            denied_extensions = []

        files_path = Path(files_path)

        def is_valid_path(p: FilePath):
            p = Path(p)

            if not match_file_extensions(
                p,
                allowed_extensions=allowed_extensions,
                denied_extensions=denied_extensions,
            ):
                self.logged_statement(
                    f"Rejecting file {p} either not in allowed extensions or in denied extensions",
                    labeled_json_data={
                        "allowed extensions": allowed_extensions,
                        "denied extensions": denied_extensions,
                    },
                )

                return False

            if not reject_dotfiles or ".terraform/modules" in str(p):
                self.logged_statement(f"File {p} is valid")
                return True

            for part in p.resolve().parts:
                if part.startswith("."):
                    self.logged_statement(f"Rejecting hidden file path {p}")
                    return False

            self.logged_statement(f"File path {p} is not hidden and is valid")
            return True

        if self.git_client is None:

            def is_valid_local_path(p: FilePath):
                p = self.local_path(p)

                if not p.is_file():
                    self.logged_statement(
                        f"Rejecting non-file {p}", verbose=True, verbosity=2
                    )
                    return False

                return is_valid_path(p)

            abs_local_file_path = self.local_path(files_path)
            if recursive:
                self.logger.info(
                    f"Getting all local files under {files_path} recursively"
                )
                paths = [
                    p
                    for p in abs_local_file_path.rglob(files_glob)
                    if is_valid_local_path(p)
                ]
            else:
                self.logger.info(f"Getting all local files under {files_path}")
                paths = [
                    p
                    for p in abs_local_file_path.glob(files_glob)
                    if is_valid_local_path(p)
                ]

            if paths_only:
                self.logger.info("Returning paths")
                return paths

            files_data = self.get_files(
                files=paths,
                relative_to_root=abs_local_file_path,
                decode=decode,
                allowed_extensions=allowed_extensions,
                denied_extensions=denied_extensions,
            )
        else:
            self.logger.info(f"Getting all remote files under {files_path}")
            contents = self.git_client.repo.get_contents(str(files_path))
            paths = []

            while contents:
                file_content = contents.pop(0)
                if file_content.type == "dir":
                    if not recursive:
                        self.logged_statement(
                            f"Skipping directory {file_content.path}, non-recursive scan"
                        )
                        continue

                    self.logged_statement(f"Scanning directory {file_content.path}")
                    contents.extend(self.git_client.repo.get_contents(file_content.path))
                    continue

                file_path = file_content.path
                if is_valid_path(file_path):
                    paths.append(file_content.path)

            if paths_only:
                return paths

            files_data = self.get_files(
                files=paths,
                decode=decode,
                allowed_extensions=allowed_extensions,
                denied_extensions=denied_extensions,
                match_dotfiles=(False if reject_dotfiles else True),
            )

        if flatten:
            self.log_results(files_data, "flat_tree")
            return files_data

        tree = {}

        def fill_tree_from_path(p: FilePath):
            b = tree

            for part in Path(p).parts:
                self.logged_statement(
                    f"Filling tree for path {p}, branch: {part}",
                    verbose=True,
                    verbosity=2,
                )
                if part not in b:
                    self.logged_statement(
                        f"New part: {part} for the tree", verbose=True, verbosity=2
                    )
                    b[part] = {}

                b = b[part]

            return b

        for file_path, file_data in files_data.items():
            cur_path = Path(file_path)
            if not is_nothing(files_match) and not files_path.match(files_match):
                self.logger.warning(
                    f"{file_path} was rejected, does not match the pattern {files_match}"
                )
                continue

            branch = fill_tree_from_path(cur_path.parent)

            file_key = cur_path.stem if stem_only else cur_path.name
            branch[file_key] = file_data

        if sanitize_keys:
            self.logger.info(
                f"Sanitizing the tree until max sanitize depth {max_sanitize_depth}"
            )
            self.log_results(tree, "raw tree")
            tree = self.sanitize_map(m=tree, max_sanitize_depth=max_sanitize_depth)

        self.log_results(tree, "tree")
        return tree
