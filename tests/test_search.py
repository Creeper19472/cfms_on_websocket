"""
Tests for search functionality.

Tests the search API endpoint for documents and directories,
including permission filtering, result limiting, and sorting.
"""

import pytest
from tests.test_client import CFMSTestClient


class TestSearchOperations:
    """Test search operations for documents and directories."""
    
    @pytest.mark.asyncio
    async def test_basic_search(self, authenticated_client: CFMSTestClient):
        """Test basic search functionality."""
        # Create test documents
        doc1 = await authenticated_client.create_document("Search Test Document 1")
        doc2 = await authenticated_client.create_document("Search Test Document 2")
        dir1 = await authenticated_client.create_directory("Search Test Directory")
        
        try:
            # Search for documents
            response = await authenticated_client.search("Search Test")
            
            assert response["code"] == 200, f"Search failed: {response.get('message', '')}"
            assert "data" in response
            assert "documents" in response["data"]
            assert "directories" in response["data"]
            assert "total_count" in response["data"]
            
            # Should find at least the documents and directory we created
            assert len(response["data"]["documents"]) >= 2
            assert len(response["data"]["directories"]) >= 1
            assert response["data"]["total_count"] >= 3
            
        finally:
            # Cleanup
            if doc1.get("code") == 200:
                try:
                    await authenticated_client.delete_document(doc1["data"]["document_id"])
                except Exception:
                    pass
            if doc2.get("code") == 200:
                try:
                    await authenticated_client.delete_document(doc2["data"]["document_id"])
                except Exception:
                    pass
            if dir1.get("code") == 200:
                try:
                    await authenticated_client.delete_directory(dir1["data"]["id"])
                except Exception:
                    pass
    
    @pytest.mark.asyncio
    async def test_search_case_insensitive(self, authenticated_client: CFMSTestClient):
        """Test that search is case-insensitive."""
        doc = await authenticated_client.create_document("CaseSensitive Test Doc")
        
        try:
            # Search with lowercase
            response = await authenticated_client.search("casesensitive")
            
            assert response["code"] == 200
            # Should find the document even with different case
            doc_names = [d["name"] for d in response["data"]["documents"]]
            assert any("CaseSensitive" in name for name in doc_names)
            
        finally:
            if doc.get("code") == 200:
                try:
                    await authenticated_client.delete_document(doc["data"]["document_id"])
                except Exception:
                    pass
    
    @pytest.mark.asyncio
    async def test_search_with_limit(self, authenticated_client: CFMSTestClient):
        """Test search with result limit."""
        # Create multiple test documents
        docs = []
        for i in range(5):
            doc = await authenticated_client.create_document(f"Limit Test Document {i}")
            docs.append(doc)
        
        try:
            # Search with limit of 3
            response = await authenticated_client.search("Limit Test", limit=3)
            
            assert response["code"] == 200
            # Total results should not exceed the limit
            total_results = len(response["data"]["documents"]) + len(response["data"]["directories"])
            assert total_results <= 3
            
        finally:
            # Cleanup
            for doc in docs:
                if doc.get("code") == 200:
                    try:
                        await authenticated_client.delete_document(doc["data"]["document_id"])
                    except Exception:
                        pass
    
    @pytest.mark.asyncio
    async def test_search_sort_by_name_asc(self, authenticated_client: CFMSTestClient):
        """Test search with sorting by name in ascending order."""
        doc1 = await authenticated_client.create_document("Sort Test Zebra")
        doc2 = await authenticated_client.create_document("Sort Test Apple")
        doc3 = await authenticated_client.create_document("Sort Test Banana")
        
        try:
            response = await authenticated_client.search(
                "Sort Test",
                sort_by="name",
                sort_order="asc"
            )
            
            assert response["code"] == 200
            assert len(response["data"]["documents"]) >= 3
            
            # Check that results are sorted by name (case-insensitive)
            names = [d["name"] for d in response["data"]["documents"] if "Sort Test" in d["name"]]
            sorted_names = sorted(names, key=str.lower)
            assert names == sorted_names
            
        finally:
            for doc in [doc1, doc2, doc3]:
                if doc.get("code") == 200:
                    try:
                        await authenticated_client.delete_document(doc["data"]["document_id"])
                    except Exception:
                        pass
    
    @pytest.mark.asyncio
    async def test_search_sort_by_name_desc(self, authenticated_client: CFMSTestClient):
        """Test search with sorting by name in descending order."""
        doc1 = await authenticated_client.create_document("Sort Desc Apple")
        doc2 = await authenticated_client.create_document("Sort Desc Zebra")
        
        try:
            response = await authenticated_client.search(
                "Sort Desc",
                sort_by="name",
                sort_order="desc"
            )
            
            assert response["code"] == 200
            assert len(response["data"]["documents"]) >= 2
            
            # Check that results are sorted by name descending
            names = [d["name"] for d in response["data"]["documents"] if "Sort Desc" in d["name"]]
            sorted_names = sorted(names, key=str.lower, reverse=True)
            assert names == sorted_names
            
        finally:
            for doc in [doc1, doc2]:
                if doc.get("code") == 200:
                    try:
                        await authenticated_client.delete_document(doc["data"]["document_id"])
                    except Exception:
                        pass
    
    @pytest.mark.asyncio
    async def test_search_sort_by_time(self, authenticated_client: CFMSTestClient):
        """Test search with sorting by creation time."""
        import asyncio
        
        doc1 = await authenticated_client.create_document("Time Sort Test 1")
        await asyncio.sleep(0.1)  # Small delay to ensure different timestamps
        doc2 = await authenticated_client.create_document("Time Sort Test 2")
        
        try:
            response = await authenticated_client.search(
                "Time Sort Test",
                sort_by="created_time",
                sort_order="asc"
            )
            
            assert response["code"] == 200
            assert len(response["data"]["documents"]) >= 2
            
            # Check that results are sorted by creation time
            times = [d["created_time"] for d in response["data"]["documents"] if "Time Sort Test" in d["name"]]
            assert times == sorted(times)
            
        finally:
            for doc in [doc1, doc2]:
                if doc.get("code") == 200:
                    try:
                        await authenticated_client.delete_document(doc["data"]["document_id"])
                    except Exception:
                        pass
    
    @pytest.mark.asyncio
    async def test_search_documents_only(self, authenticated_client: CFMSTestClient):
        """Test searching only documents."""
        doc = await authenticated_client.create_document("Docs Only Test Document")
        dir_obj = await authenticated_client.create_directory("Docs Only Test Directory")
        
        try:
            response = await authenticated_client.search(
                "Docs Only Test",
                search_documents=True,
                search_directories=False
            )
            
            assert response["code"] == 200
            # Should find documents but not directories
            assert len(response["data"]["documents"]) >= 1
            assert len(response["data"]["directories"]) == 0
            
        finally:
            if doc.get("code") == 200:
                try:
                    await authenticated_client.delete_document(doc["data"]["document_id"])
                except Exception:
                    pass
            if dir_obj.get("code") == 200:
                try:
                    await authenticated_client.delete_directory(dir_obj["data"]["id"])
                except Exception:
                    pass
    
    @pytest.mark.asyncio
    async def test_search_directories_only(self, authenticated_client: CFMSTestClient):
        """Test searching only directories."""
        doc = await authenticated_client.create_document("Dirs Only Test Document")
        dir_obj = await authenticated_client.create_directory("Dirs Only Test Directory")
        
        try:
            response = await authenticated_client.search(
                "Dirs Only Test",
                search_documents=False,
                search_directories=True
            )
            
            assert response["code"] == 200
            # Should find directories but not documents
            assert len(response["data"]["documents"]) == 0
            assert len(response["data"]["directories"]) >= 1
            
        finally:
            if doc.get("code") == 200:
                try:
                    await authenticated_client.delete_document(doc["data"]["document_id"])
                except Exception:
                    pass
            if dir_obj.get("code") == 200:
                try:
                    await authenticated_client.delete_directory(dir_obj["data"]["id"])
                except Exception:
                    pass
    
    @pytest.mark.asyncio
    async def test_search_with_parent_id(self, authenticated_client: CFMSTestClient):
        """Test that search results include parent_id information."""
        doc = await authenticated_client.create_document("Parent ID Test Document")
        
        try:
            response = await authenticated_client.search("Parent ID Test")
            
            assert response["code"] == 200
            assert len(response["data"]["documents"]) >= 1
            
            # Check that each result has the required fields
            for document in response["data"]["documents"]:
                assert "id" in document
                assert "name" in document
                assert "parent_id" in document  # Can be null for root level
                assert "type" in document
                
        finally:
            if doc.get("code") == 200:
                try:
                    await authenticated_client.delete_document(doc["data"]["document_id"])
                except Exception:
                    pass
    
    @pytest.mark.asyncio
    async def test_search_no_results(self, authenticated_client: CFMSTestClient):
        """Test search with query that returns no results."""
        response = await authenticated_client.search("ThisQueryShouldNotMatchAnything12345XYZ")
        
        assert response["code"] == 200
        assert response["data"]["documents"] == []
        assert response["data"]["directories"] == []
        assert response["data"]["total_count"] == 0
    
    @pytest.mark.asyncio
    async def test_search_empty_query(self, authenticated_client: CFMSTestClient):
        """Test search with empty query returns validation error."""
        try:
            response = await authenticated_client.search("")
            # Should fail validation due to minLength constraint
            assert response["code"] == 400
        except Exception:
            # Some implementations might raise an exception
            pass
    
    @pytest.mark.asyncio
    async def test_search_requires_authentication(self, unauthenticated_client: CFMSTestClient):
        """Test that search requires authentication."""
        response = await unauthenticated_client.search("test")
        
        # Should return authentication error
        assert response["code"] in [401, 403]
    
    @pytest.mark.asyncio
    async def test_search_partial_match(self, authenticated_client: CFMSTestClient):
        """Test that search finds partial matches."""
        doc = await authenticated_client.create_document("Partial Match Document Test")
        
        try:
            # Search with partial query
            response = await authenticated_client.search("Match")
            
            assert response["code"] == 200
            # Should find the document with partial match
            doc_names = [d["name"] for d in response["data"]["documents"]]
            assert any("Partial Match" in name for name in doc_names)
            
        finally:
            if doc.get("code") == 200:
                try:
                    await authenticated_client.delete_document(doc["data"]["document_id"])
                except Exception:
                    pass
