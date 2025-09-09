package laughcandidate.yellowribbonbe.mydata.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import laughcandidate.yellowribbonbe.auth.service.CustomUserDetails;
import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.MyDataErrorCode;
import laughcandidate.yellowribbonbe.global.response.ApiResponse;
import laughcandidate.yellowribbonbe.mydata.dto.MyDataResponse;
import laughcandidate.yellowribbonbe.mydata.service.MyDataService;
import laughcandidate.yellowribbonbe.product.entity.ProductCategory;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(name = "마이데이터")
@RestController
@RequestMapping("/mydata")
@RequiredArgsConstructor
public class MyDataController {

    private final MyDataService myDataService;

    @GetMapping("/list")
    @Operation(
        summary = "사용자 보유 금융상품 리스트 조회 API",
        description = "현재 로그인한 사용자가 보유한 금융상품 리스트를 조회합니다.")
    public ResponseEntity<ApiResponse<List<MyDataResponse>>> getMyFinancialProducts(
            @RequestParam(required = false) String category,
            @AuthenticationPrincipal CustomUserDetails customUserDetails) {
        
        List<MyDataResponse> myFinancialProducts;
        
        if (category == null || category.trim().isEmpty()) {
            myFinancialProducts = myDataService.getAllMyFinancialProducts(customUserDetails.getUserId());
        } else {
            ProductCategory productCategory = parseCategory(category);
            myFinancialProducts = myDataService.getMyFinancialProducts(customUserDetails.getUserId(), productCategory);
        }
        
        return ResponseEntity.ok(ApiResponse.ok(myFinancialProducts));
    }

    private ProductCategory parseCategory(String category) {
        if (category == null || category.trim().isEmpty()) {
            return null;
        }
        
        try {
            return ProductCategory.valueOf(category.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new CustomException(MyDataErrorCode.INVALID_MYDATA_CATEGORY, category);
        }
    }
}
