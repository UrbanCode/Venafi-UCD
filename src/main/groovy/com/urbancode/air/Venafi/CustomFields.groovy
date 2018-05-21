package com.urbancode.air.Venafi

import com.urbancode.air.Venafi.CustomField

public class CustomFields {

  def CustomFields = []

  public CustomFields() {

  }

  public addCustomField(CustomField newCustomField) {
    CustomFields.add(newCustomField)
  }

  public getNumCustomFields() {
    return CustomFields.size()
  }
  public getCustomFieldDef(Integer index) {
    return (CustomFields[index])
  }



}
