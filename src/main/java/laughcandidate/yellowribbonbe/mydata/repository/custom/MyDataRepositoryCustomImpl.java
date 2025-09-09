package laughcandidate.yellowribbonbe.mydata.repository.custom;

import com.querydsl.jpa.impl.JPAQueryFactory;
import laughcandidate.yellowribbonbe.mydata.entity.*;
import laughcandidate.yellowribbonbe.product.entity.ProductCategory;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;

import static laughcandidate.yellowribbonbe.mydata.entity.QMyDataLoan.myDataLoan;
import static laughcandidate.yellowribbonbe.mydata.entity.QMyDataDeposit.myDataDeposit;
import static laughcandidate.yellowribbonbe.mydata.entity.QMyDataSavings.myDataSavings;
import static laughcandidate.yellowribbonbe.mydata.entity.QMyDataInsurance.myDataInsurance;

@Repository
@RequiredArgsConstructor
public class MyDataRepositoryCustomImpl implements MyDataRepositoryCustom {

    private final JPAQueryFactory queryFactory;

    @Override
    public List<MyData> findByUserIdAndCategory(Long userId, ProductCategory category) {
        return switch (category) {
            case LOAN -> queryFactory
                    .selectFrom(myDataLoan)
                    .where(myDataLoan.user.id.eq(userId))
                    .fetch()
                    .stream()
                    .map(MyData.class::cast)
                    .toList();
            
            case DEPOSIT -> queryFactory
                    .selectFrom(myDataDeposit)
                    .where(myDataDeposit.user.id.eq(userId))
                    .fetch()
                    .stream()
                    .map(MyData.class::cast)
                    .toList();
            
            case SAVINGS -> queryFactory
                    .selectFrom(myDataSavings)
                    .where(myDataSavings.user.id.eq(userId))
                    .fetch()
                    .stream()
                    .map(MyData.class::cast)
                    .toList();
            
            case INSURANCE -> queryFactory
                    .selectFrom(myDataInsurance)
                    .where(myDataInsurance.user.id.eq(userId))
                    .fetch()
                    .stream()
                    .map(MyData.class::cast)
                    .toList();
        };
    }

    @Override
    public List<MyData> findByUserId(Long userId) {
        List<MyData> result = new ArrayList<>();

        List<MyDataLoan> loans = queryFactory
                .selectFrom(myDataLoan)
                .where(myDataLoan.user.id.eq(userId))
                .fetch();
        result.addAll(loans);

        List<MyDataDeposit> deposits = queryFactory
                .selectFrom(myDataDeposit)
                .where(myDataDeposit.user.id.eq(userId))
                .fetch();
        result.addAll(deposits);

        List<MyDataSavings> savings = queryFactory
                .selectFrom(myDataSavings)
                .where(myDataSavings.user.id.eq(userId))
                .fetch();
        result.addAll(savings);

        List<MyDataInsurance> insurances = queryFactory
                .selectFrom(myDataInsurance)
                .where(myDataInsurance.user.id.eq(userId))
                .fetch();
        result.addAll(insurances);
        
        return result;
    }
}
