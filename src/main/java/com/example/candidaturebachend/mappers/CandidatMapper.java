package com.example.candidaturebachend.mappers;

import com.example.candidaturebachend.dto.AnneUniversitaireDto;
import com.example.candidaturebachend.dto.CandidatDto;
import com.example.candidaturebachend.dto.DiplomeDto;
import com.example.candidaturebachend.dto.FiliereDto;
import com.example.candidaturebachend.entities.AnneUniversitaire;
import com.example.candidaturebachend.entities.Candidat;
import com.example.candidaturebachend.entities.Diplome;
import com.example.candidaturebachend.entities.Filiere;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.ToString;
import org.apache.commons.collections.CollectionUtils;
import org.dozer.DozerBeanMapper;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Service
@AllArgsConstructor
public class CandidatMapper {

    public CandidatDto candidatToDto(Candidat candidat){

        CandidatDto candidatDto = new CandidatDto();
        BeanUtils.copyProperties(candidat, candidatDto);
        return candidatDto;
    }

    public Candidat CandidatDtoToCandidat(CandidatDto candidatDto){

        Candidat candidat = new Candidat();
        BeanUtils.copyProperties(candidatDto, candidat);
        return candidat;
    }

}

