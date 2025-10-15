# setup.py
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="evilwaf",
    version="2.0.0",
    author="Matrix",
    author_email="codeleons724@gmail.com",
    description="Advanced Web Application Firewall Detection & Bypass Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/matrixleons/evilwaf",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "colorama>=0.4.4",
        "requests>=2.25.1",
        "beautifulsoup4>=4.9.3",
        "dnspython>=2.1.0",
    ],
    entry_points={
        "console_scripts": [
            "evilwaf=evilwaf:main",
        ],
    },
)
