package org.lessons.java.spring_la_mia_pizzeria_crud.service;

import java.util.List;
import java.util.Optional;

import org.lessons.java.spring_la_mia_pizzeria_crud.model.Offer;
import org.lessons.java.spring_la_mia_pizzeria_crud.repository.OfferRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

@Service
public class OfferService {

    @Autowired
    private OfferRepository offerRepository;

    public List<Offer> findAll() {
        return offerRepository.findAll();
    }

    public List<Offer> findAllSortStartOffer() {
        return offerRepository.findAll(Sort.by("start_offer"));
    }

    public Offer create(Offer offer) {
        return offerRepository.save(offer);
    }

    public Offer update(Offer offer) {
        return offerRepository.save(offer);
    }

    public Offer getById(Integer id) {
        Optional<Offer> offerAttempt = offerRepository.findById(id);
        if (offerAttempt.isEmpty()) {
            // aggiungere response entity
        }
        return offerAttempt.get();
    }

    public void deleteById(Integer id) {
        offerRepository.deleteById(id);
    }

    public void delete(Offer offer) {
        deleteById(offer.getId());

    }

}
