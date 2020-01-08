import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="shellcodeemulator-ohjeongwook",
    version="0.0.1",
    author="Matt Oh",
    author_email="jeongoh@darungrim.com",
    description="IDA Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ohjeongwook/ShellCodeEmulator",
    packages=setuptools.find_packages(),
    install_requires=[
        'unicorn',
        'windbgtool-ohjeongwook @ git+ssh://git@github.com/ohjeongwook/windbgtool@v1.1#egg=windbgtool-ohjeongwook',
        'windbgtool-ohjeongwook @ git+ssh://git@github.com/ohjeongwook/idatool@v1.1#egg=idatool-ohjeongwook',
    ],
    classifiers=[
        "Programming Language :: Python :: 2",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=2.7',
)
