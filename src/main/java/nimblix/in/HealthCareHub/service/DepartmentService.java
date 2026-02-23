package nimblix.in.HealthCareHub.service;

import nimblix.in.HealthCareHub.model.Department;

public interface DepartmentService {

    Department saveDepartment(Department department);

    Department getDepartment(Long id);

    Department updateDepartment(Long id, Department department);
}