import subprocess


def read_package_names_from_file(file_path):
    with open(file_path, "r") as file:
        package_names = [
            line.strip().split(":")[1] for line in file if line.startswith("package:")
        ]
    return package_names


def get_installed_packages():
    result = subprocess.run(
        ["adb", "shell", "pm", "list", "packages"], capture_output=True, text=True
    )
    if result.returncode == 0:
        packages = result.stdout.split("\n")
        installed_packages = [pkg.split(":")[1] for pkg in packages if pkg]
        return installed_packages
    else:
        print("Failed to get installed packages:", result.stderr)
        return []


def uninstall_packages(not_in_list, dry_run=True):
    for package in not_in_list:
        print(f"Uninstalling {package}...")
        if not dry_run:
            result = subprocess.run(
                ["adb", "shell", "pm", "uninstall", package],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                print(f"Successfully uninstalled {package}")
            else:
                print(f"Failed to uninstall {package}: {result.stderr}")
        else:
            print(f"Dry run: {package} would be uninstalled")


def main_uninstall():
    file_path = "/storage/Thesis/Data/packages.txt"
    file_packages = read_package_names_from_file(file_path)
    installed_packages = get_installed_packages()
    to_uninstall = [pkg for pkg in installed_packages if pkg not in file_packages]
    uninstall_packages(to_uninstall, dry_run=False)


if __name__ == "__main__":
    main_uninstall()
