package org.lessons.java.spring_la_mia_pizzeria_crud.service;

import java.util.List;
import java.util.Optional;

import org.lessons.java.spring_la_mia_pizzeria_crud.model.Pizza;
import org.lessons.java.spring_la_mia_pizzeria_crud.model.Offer;
import org.lessons.java.spring_la_mia_pizzeria_crud.repository.OfferRepository;
import org.lessons.java.spring_la_mia_pizzeria_crud.repository.PizzaRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

@Service
public class PizzaService {

    @Autowired
    private PizzaRepository pizzaRepository;
    @Autowired
    private OfferRepository offerRepository;

    public List<Pizza> findAll() {
        return pizzaRepository.findAll();
    }

    public List<Pizza> findAllSorteByName() {
        return pizzaRepository.findAll(Sort.by("name"));
    }

    public Optional<Pizza> findById(Integer id){
        return pizzaRepository.findById(id);
    }


    public Pizza getById(Integer id) {
        Optional<Pizza> pizzaAttempt = pizzaRepository.findById(id);
        if (pizzaAttempt.isEmpty()) {
            // aggiungere response entity
        }
        return pizzaAttempt.get();
    }

    public List<Pizza> findByName(String name) {
        return pizzaRepository.findByNameContainingAllIgnoreCase("name");
    }

    public Pizza create(Pizza pizza) {
        // aggiornamento a seguito di creazione
        return pizzaRepository.save(pizza);
    }

    public Pizza update(Pizza pizza) {
        // aggiornamento di altri campi
        return pizzaRepository.save(pizza);
    }

    public void delete(Pizza pizza){
        for(Offer offerToDelete : pizza.getOffers()){
            offerRepository.delete(offerToDelete);
        }
        pizzaRepository.delete(pizza);
    }

    public void deleteById(Integer id){
        Pizza pizza = getById(id);
        for(Offer offerToDelete : pizza.getOffers()){
            offerRepository.delete(offerToDelete);
        }
        pizzaRepository.delete(pizza);
    }

    public Boolean existsById(Integer id){
        return pizzaRepository.existsById(id);
    }

    public Boolean exists(Pizza pizza){
        return existsById(pizza.getId());
    }


}
