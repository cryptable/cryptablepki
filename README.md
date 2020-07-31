![C/C++ CI](https://github.com/cryptable/cryptablepki/workflows/C/C++%20CI/badge.svg)

Compilation
-----------

##Manual

###Install Strawberry Perl
curl from http://strawberryperl.com/download/5.30.2.1/strawberry-perl-5.30.2.1-64bit.zip
unzip and set the path
.\strawberry-perl\relocation.pl.bat
%cd%\strawberry-perl\c\bin
%cd%\strawberry-perl\perl\site\bin
%cd%\strawberry-perl\perl\bin

###Install NASM
curl from https://www.nasm.us/pub/nasm/releasebuilds/2.15.03/win64/nasm-2.15.03-win64.zip
unzip and set the path
%cd%\nasm

###Setup Visual Studio 2017

Verify the environment variable is set to:
VS150COMNTOOLS = "C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\Common7\Tools\"

TODO use powershell to figure out which Visual Studio is installed

Setting up the command line options for Visual Studio
run vcvars -> 64 bit
C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\VC\Auxiliary\Build\vcvars64.bat
run vcvars -> 32 bit
C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\VC\Auxiliary\Build\vcvars32.bat

Or open command prompt from the Visual Studio <Year> start menu:
Start -> Visual Studio 2017 -> x64 ...

###Compiling OpenSSL

For 64bit:
"C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\VC\Auxiliary\Build\vcvars64.bat"
"perl Configure --prefix="%cd%\..\..\common" --openssldir="%cd%\..\..\common" VC-WIN64A"


##Automatic

Prerequisites:
- Python 3.5 or higher
- on Windows: Visual Studio 2017 (as long as auto-detection is not supported)
- on Linux/MacOS: gcc/g++ or clanng

###Run python
On Windows:

py 1-setup-dev.py

On Linux & MasOS:

python3 1-setup-dev.py


