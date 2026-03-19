from setuptools import setup, find_packages, Extension
from pathlib import Path

long_description = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")

fast_scanner_ext = Extension(
    "chemistry._fast_scanner",
    sources=["chemistry/_fast_scanner.c"],
    extra_compile_args=["-O3", "-march=native", "-ffast-math"],
    libraries=["m"],
)

setup(
    name="evilwaf",
    version="2.5.0",
    author="Matrix Leons",
    author_email="",
    description="Advanced transparent MITM proxy and deep WAF vulnerability scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/matrixleons/evilwaf",
    license="Apache-2.0",
    packages=find_packages(exclude=["tests*", "media*"]),
    ext_modules=[fast_scanner_ext],
    python_requires=">=3.8",
    install_requires=(Path(__file__).parent / "requirements.txt")
        .read_text()
        .splitlines(),
    entry_points={
        "console_scripts": [
            "evilwaf=evilwaf:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Environment :: Console",
    ],
    keywords="waf bypass proxy mitm security penetration-testing firewall",
    include_package_data=True,
)
