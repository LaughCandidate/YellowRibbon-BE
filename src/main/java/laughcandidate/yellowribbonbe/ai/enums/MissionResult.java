package laughcandidate.yellowribbonbe.ai.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum MissionResult {
    APPROVED("승인"), 
    DECLINED("거절");
    
    private final String result;
}