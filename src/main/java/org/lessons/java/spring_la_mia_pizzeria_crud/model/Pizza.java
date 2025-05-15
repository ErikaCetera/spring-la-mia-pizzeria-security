package org.lessons.java.spring_la_mia_pizzeria_crud.model;

import java.math.BigDecimal;
import java.util.List;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@Entity
@Table( name = "pizze")
public class Pizza {


    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    @NotBlank(message = "must not be null, empty or blank")
    private String name;
    @NotBlank(message = "must not be null, empty or blank")
    private String description;
    
    private String image;
    @NotNull
    @Min(value = 0,  message = "the price cannot be negative")
    private BigDecimal price;

    //aggiunta relazione tra una pizza e 0, 1 o più offerte
    @OneToMany(mappedBy = "pizza", cascade = {CascadeType.REMOVE}) //basato su una sola pizza
    private List<Offer> offers;

    @ManyToMany
    @JoinTable(
        name = "ingredient_pizza",
        joinColumns = @JoinColumn( name = "pizza_id"),
        inverseJoinColumns = @JoinColumn( name = "ingretient_id")
        )
    private List<Ingredient> ingredients;

    public List<Ingredient> getIngredients() {
        return ingredients;
    }
    public void setIngredients(List<Ingredient> ingredients) {
        this.ingredients = ingredients;
    }

    public List<Offer> getOffers() {
        return offers;
    }
    public void setOffers(List<Offer> offers) {
        this.offers = offers;
    }
    public Integer getId() {
        return id;
    }
    public String getName() {
        return name;
    }
    public String getDescription() {
        return description;
    }
    public String getImage() {
        return image;
    }
    public BigDecimal getPrice() {
        return price;
    }

    public void setId (Integer id){
    this.id = id;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    public void setDescription(String description) {
        this.description = description;
    }
    public void setImage(String image) {
        this.image = image;
    }
    public void setPrice(BigDecimal price) {
        this.price = price;
    }

    @Override
    public String toString(){
        return String.format("%s %s %s %f ", name, description, image, price);
    }

}

