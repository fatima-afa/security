package com.example.candidaturebachend.web;

import com.example.candidaturebachend.dto.DiplomeDto;
import com.example.candidaturebachend.dto.NotesSemesterDto;

import com.example.candidaturebachend.servicesDto.serviceImpDto.DiplomeDtoServiceImpl;
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
@NoArgsConstructor
@AllArgsConstructor
@RestController
@RequestMapping("/notesSemester")
@PreAuthorize("hasAnyRole('admin')")

public class NotesSemesterController {
    @Autowired
    private DiplomeDtoServiceImpl notesSemesterService;


    @GetMapping("/all")
    public ResponseEntity<List<NotesSemesterDto>> getAllNotesSemesters() {
        List<NotesSemesterDto> notesSemesters = notesSemesterService.listNotes();
        return new ResponseEntity<>(notesSemesters, HttpStatus.OK);

    }

    /*@GetMapping("/find/{id}")
    public ResponseEntity<NotesSemesterDto> getNotesSemesterById(@PathVariable("id") Integer id) {
        NotesSemesterDto notesSemester = notesSemesterService.get(id);
        return new ResponseEntity<>(notesSemester, HttpStatus.OK);
    }*/

    @PostMapping("/add/{IDdiplome}")
    public ResponseEntity<NotesSemesterDto> addNotesSemester(@RequestBody NotesSemesterDto notesSemester,@PathVariable int IDdiplome) {
        NotesSemesterDto newNotesSemester = notesSemesterService.saveNoteSemester(notesSemester,IDdiplome);
        return new ResponseEntity<>(newNotesSemester, HttpStatus.CREATED);
    }

    @PutMapping("/update")
    public ResponseEntity<NotesSemesterDto> updateNotesSemester(@RequestBody NotesSemesterDto notesSemester, DiplomeDto diplome) {
        NotesSemesterDto updateNotesSemester = notesSemesterService.updateNoteSemester(notesSemester, diplome);
        return new ResponseEntity<>(updateNotesSemester, HttpStatus.OK);
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntity<?> deleteNotesSemester(@PathVariable("id") Integer id) {
        notesSemesterService.deleteNotes(id);
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
