"""API routes for SkillBench (SKB) - Fail-Closed Baseline."""
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, status, Path as PathParam, HTTPException
from pydantic import BaseModel
from src.api.deps import (
    require_project_capability,
    require_object_capability,
    verify_idempotency_key
)
from src.core.security import UserContext

router = APIRouter()


class PackageCreate(BaseModel):
    artifact_id: str
    name: str
    source_commit: Optional[str] = None
    license_expression: Optional[str] = None


class Package(BaseModel):
    id: str
    project_id: str
    artifact_id: str
    sha256: str
    state: str
    execution_profile: str = "fixture_only"
    revision: int = 1


class PlanCreate(BaseModel):
    package_id: str
    suite_id: str
    tasks: List[Dict[str, Any]] = []


class Plan(BaseModel):
    id: str
    project_id: str
    package_id: str
    suite_id: str
    sha256: str
    state: str
    revision: int = 1


class ExperimentCreate(BaseModel):
    plan_id: str


class Experiment(BaseModel):
    id: str
    project_id: str
    plan_id: str
    plan_sha256: str
    state: str


class Analysis(BaseModel):
    id: str
    project_id: str
    experiment_id: str
    result: Dict[str, Any]


@router.post("/projects/{project_id}/skb/packages", response_model=Package, status_code=status.HTTP_201_CREATED)
async def skb_create_package(
    project_id: str = PathParam(...),
    body: PackageCreate = ...,
    user: UserContext = Depends(require_project_capability("analyst")),
    idemp: str = Depends(verify_idempotency_key)
):
    raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED,
                        detail="Package intake unconfigured in B00 baseline.")


@router.get("/projects/{project_id}/skb/packages", response_model=List[Package], status_code=status.HTTP_200_OK)
async def skb_list_packages(
    project_id: str = PathParam(...),
    user: UserContext = Depends(require_project_capability("analyst"))
):
    return []


@router.get("/skb/packages/{package_id}", response_model=Package, status_code=status.HTTP_200_OK)
async def skb_get_package(
    package_id: str = PathParam(...),
    user: UserContext = Depends(require_object_capability("analyst"))
):
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Package not found")


@router.post("/skb/packages/{package_id}:inspect", status_code=status.HTTP_200_OK)
async def skb_inspect_package(
    package_id: str = PathParam(...),
    user: UserContext = Depends(require_object_capability("operator")),
    idemp: str = Depends(verify_idempotency_key)
):
    raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED,
                        detail="Package inspection unconfigured in B00 baseline.")


@router.post("/skb/packages/{package_id}/reviews", status_code=status.HTTP_201_CREATED)
async def skb_review_package(
    package_id: str = PathParam(...),
    user: UserContext = Depends(require_object_capability("maintainer")),
    idemp: str = Depends(verify_idempotency_key)
):
    raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED,
                        detail="Package review unconfigured in B00 baseline.")


@router.post("/projects/{project_id}/skb/suites", status_code=status.HTTP_201_CREATED)
async def skb_create_suite(
    project_id: str = PathParam(...),
    user: UserContext = Depends(require_project_capability("maintainer")),
    idemp: str = Depends(verify_idempotency_key)
):
    raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED,
                        detail="Suite creation unconfigured in B00 baseline.")


@router.get("/projects/{project_id}/skb/suites", status_code=status.HTTP_200_OK)
async def skb_list_suites(
    project_id: str = PathParam(...),
    user: UserContext = Depends(require_project_capability("analyst"))
):
    return []


@router.get("/skb/suites/{suite_id}", status_code=status.HTTP_200_OK)
async def skb_get_suite(
    suite_id: str = PathParam(...),
    user: UserContext = Depends(require_object_capability("analyst"))
):
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Suite not found")


@router.post("/projects/{project_id}/skb/plans", response_model=Plan, status_code=status.HTTP_201_CREATED)
async def skb_create_plan(
    project_id: str = PathParam(...),
    body: PlanCreate = ...,
    user: UserContext = Depends(require_project_capability("analyst")),
    idemp: str = Depends(verify_idempotency_key)
):
    raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Plan store unconfigured in B00 baseline.")


@router.get("/projects/{project_id}/skb/plans", response_model=List[Plan], status_code=status.HTTP_200_OK)
async def skb_list_plans(
    project_id: str = PathParam(...),
    user: UserContext = Depends(require_project_capability("analyst"))
):
    return []


@router.get("/skb/plans/{plan_id}", response_model=Plan, status_code=status.HTTP_200_OK)
async def skb_get_plan(
    plan_id: str = PathParam(...),
    user: UserContext = Depends(require_object_capability("analyst"))
):
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plan not found")


@router.post("/skb/plans/{plan_id}:preregister", status_code=status.HTTP_200_OK)
async def skb_preregister(
    plan_id: str = PathParam(...),
    user: UserContext = Depends(require_object_capability("maintainer")),
    idemp: str = Depends(verify_idempotency_key)
):
    raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED,
                        detail="Preregistration unconfigured in B00 baseline.")


@router.post("/projects/{project_id}/skb/experiments", response_model=Experiment, status_code=status.HTTP_201_CREATED)
async def skb_create_experiment(
    project_id: str = PathParam(...),
    body: ExperimentCreate = ...,
    user: UserContext = Depends(require_project_capability("operator")),
    idemp: str = Depends(verify_idempotency_key)
):
    raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED,
                        detail="Experiment runner unconfigured in B00 baseline.")


@router.get("/projects/{project_id}/skb/experiments", response_model=List[Experiment], status_code=status.HTTP_200_OK)
async def skb_list_experiments(
    project_id: str = PathParam(...),
    user: UserContext = Depends(require_project_capability("viewer"))
):
    return []


@router.get("/skb/experiments/{experiment_id}", response_model=Experiment, status_code=status.HTTP_200_OK)
async def skb_get_experiment(
    experiment_id: str = PathParam(...),
    user: UserContext = Depends(require_object_capability("viewer"))
):
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Experiment not found")


@router.get("/skb/experiments/{experiment_id}/trials", status_code=status.HTTP_200_OK)
async def skb_list_trials(
    experiment_id: str = PathParam(...),
    user: UserContext = Depends(require_object_capability("analyst"))
):
    return []


@router.post("/skb/experiments/{experiment_id}/analyses", response_model=Analysis, status_code=status.HTTP_201_CREATED)
async def skb_create_analysis(
    experiment_id: str = PathParam(...),
    user: UserContext = Depends(require_object_capability("analyst")),
    idemp: str = Depends(verify_idempotency_key)
):
    raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED,
                        detail="Analysis engine unconfigured in B00 baseline.")


@router.get("/skb/analyses/{analysis_id}", response_model=Analysis, status_code=status.HTTP_200_OK)
async def skb_get_analysis(
    analysis_id: str = PathParam(...),
    user: UserContext = Depends(require_object_capability("analyst"))
):
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis not found")
