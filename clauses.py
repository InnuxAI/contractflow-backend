from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List
from datetime import datetime
from bson import ObjectId
from database import db

router = APIRouter()

class Clause(BaseModel):
    title: str
    description: str
    domain: str

class ClauseInDB(Clause):
    id: str
    created_at: datetime
    last_modified: datetime

@router.get("/clauses", response_model=List[ClauseInDB])
async def get_clauses(domain: str = None):
    try:
        query = {"domain": domain} if domain else {}
        clauses = list(db.clauses.find(query))
        return [
            ClauseInDB(
                id=str(clause["_id"]),
                title=clause["title"],
                description=clause["description"],
                domain=clause["domain"],
                created_at=clause["created_at"],
                last_modified=clause["last_modified"]
            )
            for clause in clauses
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/clauses", response_model=ClauseInDB)
async def create_clause(clause: Clause):
    try:
        clause_data = clause.dict()
        clause_data["created_at"] = datetime.utcnow()
        clause_data["last_modified"] = datetime.utcnow()
        result = db.clauses.insert_one(clause_data)
        
        return ClauseInDB(
            id=str(result.inserted_id),
            **clause.dict(),
            created_at=clause_data["created_at"],
            last_modified=clause_data["last_modified"]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/clauses/{clause_id}", response_model=ClauseInDB)
async def update_clause(clause_id: str, clause: Clause):
    try:
        # Check if clause exists
        existing_clause = db.clauses.find_one({"_id": ObjectId(clause_id)})
        if not existing_clause:
            raise HTTPException(status_code=404, detail="Clause not found")

        # Update clause
        update_data = {
            "title": clause.title,
            "description": clause.description,
            "domain": clause.domain,
            "last_modified": datetime.utcnow()
        }
        db.clauses.update_one(
            {"_id": ObjectId(clause_id)},
            {"$set": update_data}
        )

        # Return updated clause
        updated_clause = db.clauses.find_one({"_id": ObjectId(clause_id)})
        return ClauseInDB(
            id=str(updated_clause["_id"]),
            title=updated_clause["title"],
            description=updated_clause["description"],
            domain=updated_clause["domain"],
            created_at=updated_clause["created_at"],
            last_modified=updated_clause["last_modified"]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/clauses/{clause_id}")
async def delete_clause(clause_id: str):
    try:
        # Check if clause exists
        existing_clause = db.clauses.find_one({"_id": ObjectId(clause_id)})
        if not existing_clause:
            raise HTTPException(status_code=404, detail="Clause not found")

        # Delete clause
        result = db.clauses.delete_one({"_id": ObjectId(clause_id)})
        if result.deleted_count == 0:
            raise HTTPException(status_code=500, detail="Failed to delete clause")

        return {"message": "Clause deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 