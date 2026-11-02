"""Document and file retrieval business service layer.

Acts as intermediate propagation layer between controllers and storage_driver.
"""

from typing import Optional
import storage_driver


def retrieve_document(requested_file: str) -> str:
    """Retrieve document by file name, propagating untrusted input to storage_driver."""
    # Line 18: Taint propagation to storage_driver
    return storage_driver.read_document_file(requested_file)
