How to Contribute
=================

We welcome contributions to enhance the functionality and usability of our software. 


...


Thank you for contributing to our project!


.. dropdown:: Writing documentation for WfExS
   :color: light

   The documentation generator is based on Sphinx, and it is being hosted at ReadTheDocs.


   Locally rendering documentation
   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

   In order to locally test the documentation generation and how the contents
   are rendered, you have to follow next steps:

   1. Create and activate a virtual environment:

   .. code-block:: bash
   
      python3 -mvenv rtd_env
      source rtd_env/bin/activate
      

   2. Install both sphinx and the dependencies:

   .. code-block:: bash

      pip install --upgrade pip wheel
      pip install sphinx readthedocs-sphinx-ext
      pip install -r docs/source/requirements.txt
   

   3. Last, you can (re)generate a local copy of the documentation with next command:

   .. code-block:: bash
      
      python -m sphinx -T -b html -d _build/doctrees -D language=en docs/source output/html
   
   
   The rendered documentation should be available at ``output/html``.





