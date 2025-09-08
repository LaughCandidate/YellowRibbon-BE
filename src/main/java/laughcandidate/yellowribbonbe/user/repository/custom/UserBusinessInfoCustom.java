package laughcandidate.yellowribbonbe.user.repository.custom;

import laughcandidate.yellowribbonbe.user.dto.response.UserBusinessInfo;

public interface UserBusinessInfoCustom {
	UserBusinessInfo findUserBusinessInfoWithId(String id);
}
