package com.example.candidaturebachend.repositories;

import com.example.candidaturebachend.entities.Candidat;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CandidatRepository extends JpaRepository<Candidat,String> {

  //  Optional<Candidat> findCandidatById(String id);
}
