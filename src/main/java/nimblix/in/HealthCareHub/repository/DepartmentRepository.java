package nimblix.in.HealthCareHub.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import nimblix.in.HealthCareHub.model.Department;


@Repository
public interface DepartmentRepository extends JpaRepository<Department, Long> {
}