package com.fsad.studentachievement.dto;

import java.util.List;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

public record SubmitTestRequest(
    @NotNull Integer attemptId,
    @NotNull Integer userId,
    @NotNull Integer moduleId,
    @NotNull @Valid List<TestAnswerRequest> answers
) {
}
