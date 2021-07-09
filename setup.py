import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open('requirements.txt', 'rt', encoding="utf-8") as f:
    install_requires = f.read().splitlines()

setuptools.setup(
    name="sentinelone-api-python-fragtastic",
    version="0.0.2",
    author="fragtastic",
    author_email="fragtastic@users.noreply.github.com",
    description="API implementation for SentinelOne",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/fragtastic/sentinelone-api-python",
    packages=setuptools.find_packages(),
    install_requires=install_requires,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.5',
)