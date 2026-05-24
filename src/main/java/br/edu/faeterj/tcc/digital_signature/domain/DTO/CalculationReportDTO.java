package br.edu.faeterj.tcc.digital_signature.domain.DTO;

import java.util.ArrayList;
import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class CalculationReportDTO {
    private String algorithmName;
    private List<String> executionSteps = new ArrayList<>();
    private String finalResult;

    public void addStep(String step) {
        this.executionSteps.add(step);
    }
}