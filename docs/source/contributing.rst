How to Contribute
=================

We welcome contributions to enhance both the functionality and usability of our software and the documentation itself. 


...


Thank you for contributing to our project!


.. dropdown:: Writing documentation for WfExS-backend
   :color: light

   WfExS-backend documentation lives at both `readthedocs` (stable tag) and `readthedocs_merge` (latest tag) branches from `<https://github.com/inab/WfExS-backend.git/tree/readthedocs_merge>`_. So, the first step to contribute is forking the repo and start adding your changes to either `readthedocs_merge` branch in your repo or a new branch derived from it. Once you are happy with the changes, then you should open a pull request from your repos branch to the `readthedocs_merge` branch at `<https://github.com/inab/WfExS-backend.git/tree/readthedocs_merge>`_.

   The documentation generator is based on Sphinx, and rendering process it is being `hosted at ReadTheDocs <https://wfexs-backend.readthedocs.io>`_.

   Locally rendering documentation
   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

   In order to locally test the documentation generation and how the contents
   are rendered, you have to follow next steps:

   1. Clone your forked repository, switch to the branch `readthedocs_merge`, change to the local directory, create and activate a virtual environment for next steps:

   .. code-block:: bash
   
      python3 -mvenv rtd_env
      source rtd_env/bin/activate
      

   2. Install both Sphinx and the dependencies. Among those dependencies is WfExS-backend itself, as the plugins used to generate both the command line and the API reference documentation pages need it properly installed in order to effectively perform their code introspection work previous to the documentation generation:

   .. code-block:: bash

      pip install --upgrade pip wheel
      pip install -r docs/source/all-requirements.txt
   

   3. Last, you can (re)generate a local copy of the documentation with next command:

   .. code-block:: bash
      
      python -m sphinx -T -b html -d _build/doctrees -D language=en docs/source output/html
   
   
   The rendered documentation should be available at ``output/html``.





