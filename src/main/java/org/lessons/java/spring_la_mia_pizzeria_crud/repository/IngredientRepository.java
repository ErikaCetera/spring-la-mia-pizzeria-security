package org.lessons.java.spring_la_mia_pizzeria_crud.repository;

import java.util.List;

import org.lessons.java.spring_la_mia_pizzeria_crud.model.Ingredient;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IngredientRepository  extends JpaRepository<Ingredient, Integer>{

    public List<Ingredient> findByNameContainingAllIgnoreCase(String name);
    

    
}
