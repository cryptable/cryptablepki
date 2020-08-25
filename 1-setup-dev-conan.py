import subprocess

def install_conan():
    subprocess.run('py -m pip install conan', shell=True)

def run_scripts():
    install_conan()
    return

if __name__ == "__main__":
    run_scripts()
