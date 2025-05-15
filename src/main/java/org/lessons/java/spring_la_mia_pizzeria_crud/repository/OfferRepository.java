package org.lessons.java.spring_la_mia_pizzeria_crud.repository;

import org.lessons.java.spring_la_mia_pizzeria_crud.model.Offer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OfferRepository extends JpaRepository< Offer, Integer > {

    
    
    
}

