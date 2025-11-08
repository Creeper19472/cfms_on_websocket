"""
Tests for document management operations.
"""

import pytest
from tests.test_client import CFMSTestClient


class TestDocumentOperations:
    """Test document CRUD operations."""
    
    def test_create_document(self, authenticated_client: CFMSTestClient):
        """Test creating a new document."""
        response = authenticated_client.create_document("Test Document")
        
        assert response["code"] == 200
        assert "data" in response
        assert "document_id" in response["data"]
        
        # Cleanup
        document_id = response["data"]["document_id"]
        authenticated_client.delete_document(document_id)
    
    def test_get_document(self, authenticated_client: CFMSTestClient, test_document: dict):
        """Test retrieving a document."""
        response = authenticated_client.get_document(test_document["document_id"])
        
        assert response["code"] == 200
        assert "data" in response
    
    def test_get_nonexistent_document(self, authenticated_client: CFMSTestClient):
        """Test retrieving a document that doesn't exist."""
        response = authenticated_client.get_document("nonexistent_doc_id")
        
        assert response["code"] != 200
    
    def test_get_document_info(self, authenticated_client: CFMSTestClient, test_document: dict):
        """Test getting document information."""
        response = authenticated_client.get_document_info(test_document["document_id"])
        
        assert response["code"] == 200
        assert "data" in response
    
    def test_rename_document(self, authenticated_client: CFMSTestClient, test_document: dict):
        """Test renaming a document."""
        new_title = "Renamed Test Document"
        response = authenticated_client.rename_document(
            test_document["document_id"],
            new_title
        )
        
        assert response["code"] == 200
        
        # Verify the rename
        info_response = authenticated_client.get_document_info(test_document["document_id"])
        assert info_response["code"] == 200
        assert info_response["data"]["title"] == new_title
    
    def test_delete_document(self, authenticated_client: CFMSTestClient):
        """Test deleting a document."""
        # Create a document
        create_response = authenticated_client.create_document("Document to Delete")
        assert create_response["code"] == 200
        document_id = create_response["data"]["document_id"]
        
        # Delete it
        delete_response = authenticated_client.delete_document(document_id)
        assert delete_response["code"] == 200
        
        # Verify it's gone
        get_response = authenticated_client.get_document(document_id)
        assert get_response["code"] != 200
    
    def test_create_document_with_empty_title(self, authenticated_client: CFMSTestClient):
        """Test creating a document with an empty title."""
        response = authenticated_client.create_document("")
        
        # Should fail validation
        assert response["code"] == 400
    
    def test_create_multiple_documents(self, authenticated_client: CFMSTestClient):
        """Test creating multiple documents."""
        document_ids = []
        
        try:
            for i in range(3):
                response = authenticated_client.create_document(f"Test Document {i}")
                assert response["code"] == 200
                document_ids.append(response["data"]["document_id"])
            
            # Verify all documents exist
            for doc_id in document_ids:
                response = authenticated_client.get_document_info(doc_id)
                assert response["code"] == 200
        finally:
            # Cleanup
            for doc_id in document_ids:
                try:
                    authenticated_client.delete_document(doc_id)
                except Exception:
                    pass


class TestDocumentWithoutAuth:
    """Test that document operations require authentication."""
    
    def test_create_document_without_auth(self, client: CFMSTestClient):
        """Test that creating a document requires authentication."""
        response = client.send_request(
            "create_document",
            {"title": "Test"},
            include_auth=False
        )
        
        assert response["code"] == 401
    
    def test_get_document_without_auth(self, client: CFMSTestClient):
        """Test that getting a document requires authentication."""
        response = client.send_request(
            "get_document",
            {"document_id": "hello"},
            include_auth=False
        )
        
        assert response["code"] == 401
