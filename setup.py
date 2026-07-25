from setuptools import setup, find_packages

setup(
    name="SeCoRa",
    version="0.1.0",
    author="nam091",
    author_email="prkatt001@gmail.com",
    description="Secure Code Review AI Agent for detecting and remediating security vulnerabilities in codebases.",
    long_description=open('README.md', encoding='utf-8').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/nam091/VulnAgent_2",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "openai",
        "anthropic",
        "python-dotenv",
        "fastapi",
        "uvicorn",
        "pydantic",
        "gitpython",
        "typing-extensions",
        "python-multipart",
        "flask",
        "waitress",
        "aiofiles",
        "setuptools"
    ],
    entry_points={
        'console_scripts': [
            'secora=main:main',  # Corrected entry point
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.12',
)
