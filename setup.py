import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="sentinelone-api-python-fragtastic",
    version="0.0.1",
    author="fragtastic",
    author_email="fragtastic@noreply.github.com",
    description="API implementation for SentinelOne",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/fragtastic/sentinelone-api-python",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.5',
)