import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

dependencies = ["pydantic", "abnf", "python-dateutil", "ecdsa"]

setuptools.setup(
    name="siws",
    version="0.0.2",
    author="Jesús Palma",
    author_email="jpalmalop@gmail.com",
    description="A python adaptation from Sign it with ethereum for Stacks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/palma9/siws-py",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=dependencies,
)
