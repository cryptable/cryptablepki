import subprocess
import os
import urllib.request
import shutil
import zipfile

def get_common_dir():
    return os.path.abspath(os.getcwd() + '/../../common')

def install_catch2():
    if not os.path.isdir("Catch2"):
        subprocess.run('git clone https://github.com/catchorg/Catch2.git', shell=True)
        append_gitignore('Catch2')
    else:
        os.chdir("Catch2")
        subprocess.run('git checkout master', shell=True)
        subprocess.run('git branch -d latest-Catch2', shell=True)
        subprocess.run('git pull', shell=True)
        os.chdir("..")

    os.chdir("Catch2")
    subprocess.run('git fetch --all --tags', shell=True)
    subprocess.run('git checkout tags/v2.12.1 -b latest-Catch2', shell=True)
    subprocess.run('cmake -DCMAKE_INSTALL_PREFIX=' + get_common_dir() + ' -Bbuild -H. -DBUILD_TESTING=OFF', shell=True)
    subprocess.run('cmake --build build/ --target install', shell=True)

    os.chdir("..")
    return

def vs_env_dict():
    # "C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\Common7\Tools\VsDevCmd.bat" -arch=amd64
    vsvar64 = '{vscomntools}VsDevCmd.bat'.format(vscomntools=os.environ['VS150COMNTOOLS'])
    cmd = [vsvar64, '-arch=amd64', '&&', 'set']
    popen = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = popen.communicate()
    if popen.wait() != 0:
        raise ValueError(stderr.decode("mbcs")) 
    output = stdout.decode("mbcs").split("\r\n")
    return dict((e[0].upper(), e[1]) for e in [p.rstrip().split("=", 1) for p in output] if len(e) == 2)


def append_gitignore(file_to_ignore):
    with open('.gitignore', 'a+') as gitignore:
        gitignore.write(file_to_ignore + '\n')

def install_openssl_win32():
    if not os.path.isdir("openssl"):
        subprocess.run('git clone https://github.com/openssl/openssl.git', shell=True)
        append_gitignore('openssl')
    else:
        os.chdir("openssl")
        subprocess.run('git pull', shell=True)
        os.chdir("..")

    openssl_build_env = os.environ.copy()
    # Visual Studio Setup
    openssl_build_env.update(vs_env_dict())

    # Strawberry perl
    if not os.path.isdir('strawberryperl'):
        with urllib.request.urlopen("http://strawberryperl.com/download/5.30.2.1/strawberry-perl-5.30.2.1-64bit.zip") as response, open("strawberryperl.zip", 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
        with zipfile.ZipFile("strawberryperl.zip", 'r') as zip_ref:
            zip_ref.extractall("strawberryperl")
        append_gitignore('strawberryperl.zip')
        append_gitignore('strawberryperl')
    subprocess.run('.\\strawberryperl\\relocation.pl.bat', shell=True)
    openssl_build_env['PATH'] = os.getcwd() + '\\strawberryperl\\c\\bin;' + openssl_build_env["PATH"]
    openssl_build_env['PATH'] = os.getcwd() + '\\strawberryperl\\perl\\site\\bin;' + openssl_build_env["PATH"]
    openssl_build_env['PATH'] = os.getcwd() + '\\strawberryperl\\perl\\bin;' + openssl_build_env["PATH"]

    # Nasm
    if not os.path.isdir('nasm-2.15.03'):
        with urllib.request.urlopen("https://www.nasm.us/pub/nasm/releasebuilds/2.15.03/win64/nasm-2.15.03-win64.zip") as response, open("nasm64.zip", 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
        with zipfile.ZipFile("nasm64.zip", 'r') as zip_ref:
            zip_ref.extractall(".")
        append_gitignore('nasm64.zip')
        append_gitignore('nasm-2.15.03')
    openssl_build_env['PATH'] = os.getcwd() + '\\nasm-2.15.03;' + openssl_build_env["PATH"]

    # OpenSSL
    os.chdir("openssl")
    pwait = subprocess.run('git fetch --all --tags', shell=True)
    pwait = subprocess.run('git checkout OpenSSL_1_1_1-stable', shell=True)
    pwait = subprocess.Popen('perl Configure --prefix="' + get_common_dir() + '" --openssldir="' + get_common_dir() + '" no-ssl2 no-ssl3 no-shared VC-WIN64A', env=openssl_build_env)
    pwait.wait()
    pwait = subprocess.Popen('nmake', env=openssl_build_env)
    pwait.wait()
    pwait = subprocess.Popen('nmake test', env=openssl_build_env)
    pwait.wait()
    pwait = subprocess.Popen('nmake install', env=openssl_build_env)
    pwait.wait()
    os.chdir("..")
    return

def install_openssl():
    if not os.path.isdir("openssl"):
        subprocess.run('git clone https://github.com/openssl/openssl.git', shell=True)
        append_gitignore('openssl')
    else:
        os.chdir("openssl")
        subprocess.run('git pull', shell=True)
        os.chdir("..")

    os.chdir("openssl")
    subprocess.run('git fetch --all --tags', shell=True)
    subprocess.run('git checkout OpenSSL_1_1_1-stable', shell=True)
    subprocess.run('./config --prefix=' + get_common_dir() + ' --openssldir=' + get_common_dir() + ' no-ssl2 no-ssl3 no-shared -d', shell=True)
    subprocess.run('make', shell=True)
    subprocess.run('make test', shell=True)
    subprocess.run('make install', shell=True)
    os.chdir("..")
    return


def run_scripts():
    if not os.path.isdir("3rd-party"):
        os.mkdir("3rd-party")
    os.chdir("3rd-party")
    install_catch2()
    if os.name == 'nt':
        print('running windows setup')
        install_openssl_win32()
    else:
        print('running linux setup')
        install_openssl()
    os.chdir("..")
    return

if __name__ == "__main__":
    run_scripts()
