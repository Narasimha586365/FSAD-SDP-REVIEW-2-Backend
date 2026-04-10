package com.fsad.studentachievement.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record TestAnswerRequest(@NotNull Integer questionId, @NotBlank String selectedAnswer) {
}
