package laughcandidate.yellowribbonbe.mydata.service;

import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.MyDataErrorCode;
import laughcandidate.yellowribbonbe.mydata.dto.*;
import laughcandidate.yellowribbonbe.mydata.entity.*;
import laughcandidate.yellowribbonbe.mydata.repository.MyDataRepository;
import laughcandidate.yellowribbonbe.product.entity.ProductCategory;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class MyDataService {

    private final MyDataRepository myDataRepository;

    public List<MyDataResponse> getMyFinancialProducts(Long userId, ProductCategory category) {
        List<MyData> myDataList = myDataRepository.findByUserIdAndCategory(userId, category);
        
        if (myDataList.isEmpty()) {
            throw new CustomException(MyDataErrorCode.MYDATA_CATEGORY_NOT_FOUND, 
                    category.getDescription());
        }
        
        return myDataList.stream()
                .map(this::convertToResponse)
                .toList();
    }

    public List<MyDataResponse> getAllMyFinancialProducts(Long userId) {
        List<MyData> myDataList = myDataRepository.findByUserId(userId);
        
        if (myDataList.isEmpty()) {
            throw new CustomException(MyDataErrorCode.MYDATA_NOT_FOUND);
        }
        
        return myDataList.stream()
                .map(this::convertToResponse)
                .toList();
    }

    private MyDataResponse convertToResponse(MyData myData) {
        return switch (myData.getCategory()) {
            case LOAN -> MyDataLoanResponse.from((MyDataLoan) myData);
            case DEPOSIT -> MyDataDepositResponse.from((MyDataDeposit) myData);
            case SAVINGS -> MyDataSavingsResponse.from((MyDataSavings) myData);
            case INSURANCE -> MyDataInsuranceResponse.from((MyDataInsurance) myData);
        };
    }
}
