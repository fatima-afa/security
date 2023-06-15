package com.example.candidaturebachend.web;

import com.example.candidaturebachend.Exceptions.CandidateNotFoundException;
import com.example.candidaturebachend.dto.CandidatDto;
import com.example.candidaturebachend.entities.Candidat;
import com.example.candidaturebachend.repositories.CandidatRepository;
import com.example.candidaturebachend.servicesDto.serviceImpDto.CandidatDtoServiceImp;
import lombok.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@RestController
@RequestMapping("/candidat")
public class CandidatController {
    @Autowired
    private CandidatDtoServiceImp candidatDtoServiceImp;
    @Autowired
    CandidatRepository candidatRepo;

    @GetMapping("/all")
    public ResponseEntity<List<CandidatDto>> getAllCandidats() {
        List<CandidatDto> candidatDtos = candidatDtoServiceImp.listCandidats();
        return new ResponseEntity<>(candidatDtos, HttpStatus.OK);

    }
    @GetMapping("/find/{id}")
    public ResponseEntity<CandidatDto> getCandidatById(@PathVariable("id") String id) throws CandidateNotFoundException {
        CandidatDto candidat = candidatDtoServiceImp.getCandidat(id);
        return new ResponseEntity<>(candidat, HttpStatus.OK);
    }

    @PostMapping("/add")
    public ResponseEntity<CandidatDto> addCandidat(@RequestBody CandidatDto candidat) {
        CandidatDto newCandidat = candidatDtoServiceImp.saveCandidat(candidat);
        return new ResponseEntity<>(newCandidat, HttpStatus.CREATED);
    }
    @PutMapping("/update")
    public ResponseEntity<CandidatDto> updateCandidat(@RequestBody CandidatDto candidat) {
        CandidatDto updateCandidat = candidatDtoServiceImp.updateCandidat(candidat);
        return new ResponseEntity<>(updateCandidat, HttpStatus.OK);
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntity<?> deleteCandidat(@PathVariable("id") String id) {
        candidatDtoServiceImp.deleteCandidat(id);
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
