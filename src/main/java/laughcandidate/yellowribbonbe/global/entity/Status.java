package laughcandidate.yellowribbonbe.global.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Status {
    PENDING("PENDING"),
    COMPLETE("COMPLETE"),
    REJECTED("REJECTED");

    private final String status;
}
