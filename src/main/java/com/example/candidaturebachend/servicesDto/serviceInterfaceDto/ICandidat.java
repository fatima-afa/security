package com.example.candidaturebachend.servicesDto.serviceInterfaceDto;

import com.example.candidaturebachend.Exceptions.CandidateNotFoundException;
import com.example.candidaturebachend.Exceptions.fileNotFoundException;
import com.example.candidaturebachend.dto.CandidatDto;
import com.example.candidaturebachend.dto.DiplomeDto;
import com.example.candidaturebachend.dto.FichierDto;
import com.example.candidaturebachend.entities.Candidat;

import java.util.List;

public interface ICandidat {
    CandidatDto saveCandidat(CandidatDto candidatDto);
    List<CandidatDto> listCandidats();
    CandidatDto getCandidat(String id) throws CandidateNotFoundException;
    CandidatDto updateCandidat(CandidatDto candidatDto);
    void deleteCandidat(String id);
}
