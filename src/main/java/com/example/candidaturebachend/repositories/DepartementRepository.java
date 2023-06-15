package com.example.candidaturebachend.repositories;

import com.example.candidaturebachend.entities.ChefDepartement;
import com.example.candidaturebachend.entities.Departement;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface DepartementRepository extends JpaRepository<Departement,Integer> {

    //Optional<Departement> findDepartementById(Integer id);
}
