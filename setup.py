import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()


setuptools.setup(
    name="sa_request",
    version="0.9.1b",
    author="Amir Pourjafari",
    author_email="amir.pourjafari@gmail.com",
    description="Django Simple Processor",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/sauditore/SARequest/",
    project_urls={
        "Bug Tracker": "https://github.com/sauditore/SARequest/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.6",
    install_requires=["khayyam", "django"]
)
