Building
========
Use `sphinx-apidoc ../ -o source/ -e -f` to generate sources and insert them into `source/`. 

Edit `source/config.py` to bump the version or change settings

To build run: `make html`

Docs can be found in `docs/build/html/index.html`

`requirements.txt` found in this folder contains sphinx and the sphinx theme 
