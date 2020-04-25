import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="id-roles",
    version="0.0.4",
    author="Wouter de Jong",
    author_email="author@example.com",
    description="Id-manager roles package",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/W-DEJONG/id-roles",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Topic :: Security"
    ],
    python_requires='>=3.6',
)
