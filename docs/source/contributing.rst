Contributing
============


Types of contributions
----------------------

- Report bugs
- Fix bugs
- Implement features 



Development tips
----------------

All the development dependencies are declared at `dev-requirements.txt` and 
`mypy-requirements.txt`. 

To install development requistites:

.. code-block:: bash
   
   python3 -m venv .pyWEenv
   source .pyWEenv/bin/activate
   pip install --upgrade pip wheel
   pip install -r requirements.txt --> this is installed with the basic installer 
   pip install -r dev-requirements.txt
   pip install -r mypy-requirements.txt


