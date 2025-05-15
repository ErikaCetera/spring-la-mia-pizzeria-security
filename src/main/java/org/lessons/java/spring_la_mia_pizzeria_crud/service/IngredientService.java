package org.lessons.java.spring_la_mia_pizzeria_crud.service;

import java.util.List;
import java.util.Optional;

import org.lessons.java.spring_la_mia_pizzeria_crud.model.Ingredient;
import org.lessons.java.spring_la_mia_pizzeria_crud.model.Pizza;
import org.lessons.java.spring_la_mia_pizzeria_crud.repository.IngredientRepository;
import org.lessons.java.spring_la_mia_pizzeria_crud.repository.PizzaRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;


@Service
public class IngredientService {

    @Autowired
    private IngredientRepository ingredientRepository;
    @Autowired
    private PizzaRepository pizzaRepository;

    public List<Ingredient> findAll() {
        return ingredientRepository.findAll();
    }

    public List<Ingredient> findAllSorteByName() {
        return ingredientRepository.findAll(Sort.by("name"));
    }

    public Ingredient getById(Integer id) {
        Optional<Ingredient> ingredientAttempt = ingredientRepository.findById(id);
        if (ingredientAttempt.isEmpty()) {
            // aggiungere response entity
        }
        return ingredientAttempt.get();
    }

    public List<Ingredient> findByName(String name) {
        return ingredientRepository.findByNameContainingAllIgnoreCase("name");
    }

    public Ingredient create(Ingredient ingredient) {
        // aggiornamento a seguito di creazione
        return ingredientRepository.save(ingredient);
    }

    public Ingredient update(Ingredient ingredient) {
        // aggiornamento a seguito di creazione
        return ingredientRepository.save(ingredient);
    }

    public void deleteById(Integer id) {
        Ingredient ingredient = getById(id);
        for (Pizza pizza : ingredient.getPizze()) {
            pizza.getIngredients().remove(ingredient);
            pizzaRepository.save(pizza);
        }

        ingredientRepository.deleteById(id);
    }

    public void delete(Ingredient ingredient) {
    for (Pizza pizza : ingredient.getPizze()) {
        pizza.getIngredients().remove(ingredient);
        pizzaRepository.save(pizza);
    }
    ingredientRepository.delete(ingredient);
}

}
