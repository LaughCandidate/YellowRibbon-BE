package laughcandidate.yellowribbonbe.mydata.repository;

import laughcandidate.yellowribbonbe.mydata.entity.MyData;
import laughcandidate.yellowribbonbe.mydata.repository.custom.MyDataRepositoryCustom;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface MyDataRepository extends JpaRepository<MyData, Long>, MyDataRepositoryCustom {
}
