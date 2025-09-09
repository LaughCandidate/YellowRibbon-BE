package laughcandidate.yellowribbonbe.admin.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import laughcandidate.yellowribbonbe.admin.dto.request.MissionStatusUpdateRequest;
import laughcandidate.yellowribbonbe.global.entity.Status;
import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.AdminErrorCode;
import laughcandidate.yellowribbonbe.mission.entity.MissionSubmit;
import laughcandidate.yellowribbonbe.mission.repository.MissionSubmitRepository;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AdminMissionService {

    private final MissionSubmitRepository missionSubmitRepository;

    @Transactional
    public void updateMissionStatus(Long missionSubmitId, MissionStatusUpdateRequest request) {
        MissionSubmit missionSubmit = missionSubmitRepository.findById(missionSubmitId)
            .orElseThrow(() -> new CustomException(AdminErrorCode.MISSION_SUBMIT_NOT_FOUND));

        validateStatusTransition(missionSubmit.getStatus(), request.status());

        missionSubmit.updateStatus(request.status());
        
        if (request.reason() != null) {
            missionSubmit.updateReason(request.reason());
        }
    }

    private void validateStatusTransition(Status currentStatus, Status newStatus) {
        if (currentStatus == newStatus) {
            throw new CustomException(AdminErrorCode.INVALID_STATUS_TRANSITION);
        }

        switch (currentStatus) {
            case PENDING -> {
                if (newStatus != Status.COMPLETE && newStatus != Status.REJECTED) {
                    throw new CustomException(AdminErrorCode.INVALID_STATUS_TRANSITION);
                }
            }
            case COMPLETE -> {
                if (newStatus != Status.REJECTED) {
                    throw new CustomException(AdminErrorCode.INVALID_STATUS_TRANSITION);
                }
            }
            case REJECTED -> {
                if (newStatus != Status.PENDING) {
                    throw new CustomException(AdminErrorCode.INVALID_STATUS_TRANSITION);
                }
            }
        }
    }
}