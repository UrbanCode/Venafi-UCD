package com.urbancode.air.Venafi

public class CustomField {

  String label
  String guid
  String regularExpression
  String defaultValue

  public CustomField(String label, String guid, String regularExpression, String defaultValue) {
    this.label = label
    this.guid = guid
    this.regularExpression = regularExpression
    this.defaultValue = defaultValue
  }
  public getLabel() {
    return label
  }
  public getGUID() {
    return guid
  }

}
