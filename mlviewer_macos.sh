#!/bin/bash

# Use python3 if python is not available
if command -v python &> /dev/null; then
    PYTHON_CMD=python
elif command -v python3 &> /dev/null; then
    PYTHON_CMD=python3
else
    echo "Need to install python >= 3.8.0 to run mlviewer."
    exit 1
fi

# Check if installed python version is 3.8.0+
if [ "$(${PYTHON_CMD} -c 'import sys; print(sys.version_info >= (3, 8))')" != "True" ]; then
    echo "Python 3.8.0+ is required."
    exit 1
fi

# Check if the virtual environment already exists
if [ ! -d "venv" ]; then
    # Create python virtual environment
    ${PYTHON_CMD} -m venv ./venv

    # Activate venv
    source venv/bin/activate

    # Install requirements
    pip install -r requirements.txt

    # Install capstone based on architecture
	  pip install capstone
else
    # Activate venv
    source venv/bin/activate
fi

# Run
${PYTHON_CMD} main.py
