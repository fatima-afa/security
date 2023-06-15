package com.example.candidaturebachend.web;

import com.example.candidaturebachend.Exceptions.FiliereNotFoundException;
import com.example.candidaturebachend.dto.FiliereDto;
import com.example.candidaturebachend.entities.Filiere;
import com.example.candidaturebachend.enums.TypeFormation;
import com.example.candidaturebachend.repositories.FiliereRepository;
import com.example.candidaturebachend.servicesDto.serviceImpDto.FiliereDtoServiceImpl;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Data
@Builder
@AllArgsConstructor
@RestController
@RequestMapping("/filiere")
@PreAuthorize("hasAnyRole('admin')")

public class FiliereController {
    private FiliereDtoServiceImpl filiereService;
   // FiliereRepository filiereRepo;


    @GetMapping("/all")
    public ResponseEntity<List<FiliereDto>> getAllFilieres() {
        List<FiliereDto> filieres = filiereService.listFilieres();
        return new ResponseEntity<>(filieres, HttpStatus.OK);

    }

    @GetMapping("/findId/{id}")
    public ResponseEntity<FiliereDto> getFiliereById(@PathVariable("id") int id) throws FiliereNotFoundException {
        FiliereDto filiere = filiereService.getFiliereById(id);
        return new ResponseEntity<>(filiere, HttpStatus.OK);
    }

    @GetMapping("/findFormation/{formation}")
    public ResponseEntity<List<FiliereDto>> getFiliereByFormation(@PathVariable("formation") TypeFormation formation){
        List<FiliereDto> filieres = filiereService.getFiliereByFormation(formation);
        return new ResponseEntity<>(filieres, HttpStatus.OK);
    }
    @PostMapping("/add")
    public ResponseEntity<FiliereDto> addFiliere(@RequestBody FiliereDto filiere) {
        FiliereDto newFiliere = filiereService.savefiliere(filiere);
        return new ResponseEntity<>(newFiliere, HttpStatus.CREATED);
    }

  /*  @PutMapping("/update")
    public ResponseEntity<Filiere> updateFiliere(@RequestBody Filiere filiere) {
        Filiere updateFiliere = filiereService.updateFiliere(filiere);
        return new ResponseEntity<>(updateFiliere, HttpStatus.OK);
    }*/



    @DeleteMapping("/delete/{id}")
    public ResponseEntity<?> deleteFiliere(@PathVariable("id") Integer id) {
        filiereService.deletFiliere(id);
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
